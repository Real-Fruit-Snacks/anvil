package smbclient

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/smb"

	"anvil/internal/ui"
)

// DefaultDownloadChunkSize is the per-request read size for Download when
// DownloadOptions.ChunkSize is zero. 64 KiB rides a single SMB2 credit on
// connections without LARGE_MTU (pkg/third_party/smb2 caps single-credit
// payloads at 64 KiB), so it never triggers the library's internal
// multi-request splitting; bigger values work but buy nothing over LAN RTTs.
const DefaultDownloadChunkSize = 64 << 10

// downloadStateVersion is the on-disk schema version of downloadState.
// Bump when the layout changes; loaders reject anything else so a stale
// state file can never be misread as valid progress.
const downloadStateVersion = 1

// DownloadOptions controls one Download run.
type DownloadOptions struct {
	// Resume continues an interrupted download from its saved state. The
	// remote file's size and last-write time must still match the state;
	// any mismatch fails with an error naming --restart. With no state on
	// disk, Resume degrades to a fresh download.
	Resume bool
	// Restart discards any saved state and re-downloads from byte zero.
	Restart bool
	// ChunkSize is the read chunk size in bytes; zero selects
	// DefaultDownloadChunkSize. A resumed download must use the same chunk
	// size it started with (recorded in the state file).
	ChunkSize int
	// MaxChunks stops the run after this many newly fetched chunks, leaving
	// resumable state behind (0 = no limit). Exists for staged pulls and
	// for exercising resume without killing the process mid-transfer.
	MaxChunks int
}

// DownloadResult reports what one Download run did. Done is false when the
// run stopped early (MaxChunks); the state file at StatePath then holds
// resumable progress. On Done, StatePath is removed.
type DownloadResult struct {
	BytesWritten int64         // bytes fetched and written during THIS run
	TotalSize    int64         // remote file size in bytes
	Done         bool          // true when the local file is complete
	Resumed      bool          // true when prior state let this run skip chunks
	StatePath    string        // progress-state file (exists unless Done)
	Elapsed      time.Duration // wall time of the run
}

// downloadState is the JSON progress record for one interrupted download,
// persisted at ~/.anvil/downloads/download_<md5(abs local path)>.json.
// Chunks is the ground truth: chunk index → bytes written at that chunk's
// offset. A chunk is only recorded after its WriteAt lands, so a kill
// between write and record re-fetches at most one chunk — safe, because
// resume overwrites the same offsets.
type downloadState struct {
	Version     int             `json:"version"`
	RemotePath  string          `json:"remotePath"`  // informational; identity is size+mtime
	LocalPath   string          `json:"localPath"`   // as passed to Download
	Size        int64           `json:"size"`        // remote size at start
	ModTimeUnix int64           `json:"modTimeUnix"` // remote last-write, Unix nanos
	ChunkSize   int             `json:"chunkSize"`
	BytesDone   int64           `json:"bytesDone"` // sum of Chunks; display convenience
	Chunks      map[int64]int64 `json:"chunks"`    // chunk index → bytes written
}

// Download fetches remotePath (on the currently selected share) to
// localPath in chunkSize steps, persisting progress after every chunk so an
// interrupted run can continue where it stopped. It rides the existing SMB
// session (one tree connect, like Stat) — no new channel is opened.
//
// The local file is pre-sized to the remote length up front, so every chunk
// is a positioned WriteAt and the resume check can trust the local size.
// On completion the state file is removed and the local mtime is set to the
// remote last-write time (best-effort, for sensible listings).
func (s *Session) Download(remotePath, localPath string, opts DownloadOptions) (DownloadResult, error) {
	var res DownloadResult
	if opts.Resume && opts.Restart {
		return res, fmt.Errorf("--resume and --restart cannot be used together")
	}
	if s.share == "" {
		return res, fmt.Errorf("no share selected — use <share> first")
	}
	if fi, err := os.Stat(localPath); err == nil && fi.IsDir() {
		return res, fmt.Errorf("%s is a directory", localPath)
	}
	chunkSize := opts.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultDownloadChunkSize
	}

	start := time.Now()
	// Resolve like ls/get: pkg/smb joins arguments against its internal
	// currentPath, but Download opens the file on a freshly mounted tree
	// that has no cwd — so join explicitly (same pattern as Find).
	norm := path.Join(s.client.GetCurrentPath(), smbPath(remotePath))

	sh, err := s.client.Session.Mount(s.share)
	if err != nil {
		return res, mapDownloadError(err)
	}
	defer sh.Umount()

	rf, err := sh.Open(norm)
	if err != nil {
		return res, mapDownloadError(err)
	}
	defer rf.Close()

	fi, err := rf.Stat()
	if err != nil {
		return res, mapDownloadError(err)
	}
	if fi.IsDir() {
		return res, fmt.Errorf("%s is a directory on the target", remotePath)
	}
	size := fi.Size()
	modTime := fi.ModTime().UnixNano()
	res.TotalSize = size

	sp, err := downloadStatePath(localPath)
	if err != nil {
		return res, err
	}
	res.StatePath = sp

	st, resumed, err := prepareDownloadState(sp, remotePath, localPath, size, modTime, chunkSize, opts)
	if err != nil {
		return res, err
	}
	res.Resumed = resumed
	ui.Debugf("download: %d bytes, chunk %d, resumed=%v, state %s", size, chunkSize, resumed, sp)

	lf, err := openLocalFile(localPath, resumed)
	if err != nil {
		return res, fmt.Errorf("open local file: %v", err)
	}
	defer lf.Close() // success path closes explicitly first; the double close is a harmless no-op
	// Pre-size to the full remote length: chunks then land at their final
	// offsets regardless of fetch order, and a state-vs-local size check on
	// resume stays meaningful. Windows extends with zeros (not sparse).
	if err := lf.Truncate(size); err != nil {
		return res, fmt.Errorf("pre-size local file: %v", err)
	}

	if !resumed {
		// Fresh run: record the initial state so even a kill before the
		// first chunk leaves a resumable marker.
		if err := writeDownloadState(sp, st); err != nil {
			return res, fmt.Errorf("save download state: %v", err)
		}
	}

	buf := make([]byte, chunkSize)
	total := numChunks(size, int64(chunkSize))
	chunksThisRun := 0
	for idx := int64(0); idx < total; idx++ {
		off, length := chunkRange(idx, size, int64(chunkSize))
		if st.Chunks[idx] == length {
			continue // recorded complete by an earlier run
		}
		n, rerr := rf.ReadAt(buf[:length], off)
		// smb2's ReadAt returns io.EOF only when the offset is already at/past
		// EOF (n==0); a chunk straddling EOF comes back short with nil error.
		// Size was statted up front, so any short read means the file shrank
		// under us — bail out instead of silently truncating progress.
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return res, mapDownloadError(rerr)
		}
		if int64(n) != length {
			return res, fmt.Errorf("remote file shrank during download (got %d of %d bytes at offset %d) — start over with --restart",
				n, length, off)
		}
		if _, werr := lf.WriteAt(buf[:length], off); werr != nil {
			return res, fmt.Errorf("write local file: %v", werr)
		}
		st.Chunks[idx] = length
		st.BytesDone += length
		if err := writeDownloadState(sp, st); err != nil {
			return res, fmt.Errorf("save download state: %v", err)
		}
		res.BytesWritten += length
		chunksThisRun++
		if opts.MaxChunks > 0 && chunksThisRun >= opts.MaxChunks {
			res.Elapsed = time.Since(start)
			return res, nil // Done stays false; state on disk holds progress
		}
	}

	lf.Close()
	// Best-effort: mirror the remote mtime for sensible local listings. Not
	// part of resume validation (that reads the live remote stat).
	if err := os.Chtimes(localPath, time.Now(), fi.ModTime()); err != nil {
		ui.Debugf("download: chtimes %s: %v", localPath, err)
	}
	if err := os.Remove(sp); err != nil {
		ui.Debugf("download: remove state %s: %v", sp, err)
	}
	res.Done = true
	res.Elapsed = time.Since(start)
	return res, nil
}

// prepareDownloadState decides what a run does with any previously saved
// state and returns the state to work from (fresh or loaded). Under
// --resume every inconsistency (corrupt state, changed remote, missing or
// resized local partial) is a hard error naming --restart: the user asked
// to continue a specific transfer, so silently discarding its progress
// would hide real divergence. Under a plain download the stale state is
// simply discarded — get semantics always overwrite.
func prepareDownloadState(sp, remotePath, localPath string, size, modTime int64, chunkSize int, opts DownloadOptions) (st *downloadState, resumed bool, err error) {
	if opts.Restart {
		removeStateQuiet(sp)
	} else if existing, lerr := loadDownloadState(sp); lerr != nil {
		if opts.Resume {
			return nil, false, fmt.Errorf("download state %s is unreadable (%v) — start over with --restart", sp, lerr)
		}
		removeStateQuiet(sp) // corrupt leftover; a plain download overwrites anyway
	} else if existing != nil {
		switch {
		case !opts.Resume:
			removeStateQuiet(sp)
		default:
			if rerr := checkResumeState(existing, size, modTime, chunkSize, localPath); rerr != nil {
				return nil, false, rerr
			}
			existing.recount()
			return existing, true, nil
		}
	}
	return &downloadState{
		Version:     downloadStateVersion,
		RemotePath:  remotePath,
		LocalPath:   localPath,
		Size:        size,
		ModTimeUnix: modTime,
		ChunkSize:   chunkSize,
		Chunks:      make(map[int64]int64),
	}, false, nil
}

// checkResumeState validates saved progress against the live remote facts
// and the local partial file. localPath is stat'ed here (the only I/O) so
// the remote-side checks stay pure arithmetic.
func checkResumeState(st *downloadState, size, modTime int64, chunkSize int, localPath string) error {
	if st.Size != size || st.ModTimeUnix != modTime {
		return fmt.Errorf("remote file changed since the interrupted download (size %d→%d or last-write time differs) — start over with --restart",
			st.Size, size)
	}
	if st.ChunkSize != chunkSize {
		return fmt.Errorf("interrupted download used chunk size %d (now %d) — start over with --restart",
			st.ChunkSize, chunkSize)
	}
	lfi, err := os.Stat(localPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("local partial file %s is gone — start over with --restart", localPath)
	case err != nil:
		return fmt.Errorf("stat local partial file: %v", err)
	case lfi.Size() != st.Size:
		return fmt.Errorf("local partial file %s was modified (size %d, expected %d) — start over with --restart",
			localPath, lfi.Size(), st.Size)
	}
	return nil
}

// recount recomputes BytesDone from the chunk map, counting only chunks
// whose recorded length matches their expected length (a hand-edited or
// torn record simply marks that chunk pending again).
func (st *downloadState) recount() {
	var done int64
	for idx, n := range st.Chunks {
		if _, length := chunkRange(idx, st.Size, int64(st.ChunkSize)); n == length {
			done += n
		}
	}
	st.BytesDone = done
}

// numChunks returns the chunk count for size at chunkSize.
func numChunks(size, chunkSize int64) int64 {
	if size <= 0 {
		return 0
	}
	return (size + chunkSize - 1) / chunkSize
}

// chunkRange returns the file offset and expected length of chunk idx.
// The last chunk is short unless size is chunk-aligned.
func chunkRange(idx, size, chunkSize int64) (off, length int64) {
	off = idx * chunkSize
	length = chunkSize
	if rem := size - off; rem < length {
		length = rem
	}
	return off, length
}

// openLocalFile opens the destination for positioned writes: truncated when
// starting fresh, kept as-is when resuming (checkResumeState already
// verified its size).
func openLocalFile(localPath string, resumed bool) (*os.File, error) {
	flag := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if resumed {
		flag = os.O_WRONLY
	}
	return os.OpenFile(localPath, flag, 0644)
}

// --- state file -----------------------------------------------------------

// anvilStateDir introduces anvil's per-user state directory convention:
// ~/.anvil (%USERPROFILE%\.anvil on Windows) holds local persistent state,
// created 0700; each feature gets a subdirectory (downloads/ here) and
// files inside are written 0600. Modes are advisory on Windows — NTFS ACLs
// govern real access — but matter on the Linux build.
func anvilStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate home directory: %v", err)
	}
	return filepath.Join(home, ".anvil"), nil
}

// downloadStateDir returns (creating if needed) the downloads state dir.
func downloadStateDir() (string, error) {
	root, err := anvilStateDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "downloads")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create state directory: %v", err)
	}
	return dir, nil
}

// downloadStatePath names the state file for a destination path:
// download_<md5 of the absolute local path>.json. Keying on the local path
// (not the remote one) means re-running the same command line always finds
// its prior progress, whatever the remote path was.
func downloadStatePath(localPath string) (string, error) {
	dir, err := downloadStateDir()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(localPath)
	if err != nil {
		return "", fmt.Errorf("resolve local path: %v", err)
	}
	sum := md5.Sum([]byte(abs))
	return filepath.Join(dir, "download_"+hex.EncodeToString(sum[:])+".json"), nil
}

// loadDownloadState reads a state file. A missing file is (nil, nil) — no
// prior progress. Anything unparsable or from another schema version is an
// error; callers decide whether that wedges the run (--resume) or gets
// discarded (plain download).
func loadDownloadState(path string) (*downloadState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st downloadState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("corrupt JSON: %v", err)
	}
	if st.Version != downloadStateVersion {
		return nil, fmt.Errorf("unsupported state version %d", st.Version)
	}
	if st.Chunks == nil {
		st.Chunks = make(map[int64]int64)
	}
	return &st, nil
}

// writeDownloadState persists st atomically: marshal → temp file in the
// same directory → rename onto the live path. Windows refuses
// rename-over-existing, so there the destination is removed first — a small
// non-atomic window, accepted and contained (a lost state file just
// restarts the download).
func writeDownloadState(path string, st *downloadState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %v", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			os.Remove(tmp)
			return err
		}
		if err2 := os.Rename(tmp, path); err2 != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

// removeStateQuiet deletes a state file, ignoring absence; failures are
// debug-logged only (a leftover state file is cosmetic — the next plain
// download discards it).
func removeStateQuiet(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		ui.Debugf("download: remove state %s: %v", path, err)
	}
}

// mapDownloadError translates smb2-layer download failures into the short
// themed messages the shell prints. The smb2 client wraps server faults as
// *os.PathError → *smb2.ResponseError, translating OBJECT_NAME_NOT_FOUND to
// os.ErrNotExist and ACCESS_DENIED to os.ErrPermission (conn.go), so typed
// checks cover the common cases; the raw erref text catches the rest.
func mapDownloadError(err error) error {
	switch {
	case smb.IsNotFound(err), errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("no such file on the target")
	case smb.IsSharingViolation(err):
		return fmt.Errorf("file is locked on the target (sharing violation)")
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("access denied")
	case strings.Contains(err.Error(), "{Access Denied}"): // STATUS_ACCESS_DENIED, untranslated
		return fmt.Errorf("access denied")
	}
	return err
}

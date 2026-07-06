/*
Copyright (c) 2026 Security Research

Package svc implements the Service Layer for Knowledge Source (KS) management,
mirroring the "SVC" patterns found in Gitea for semantically robust code storage.
Every Knowledge Source is treated as a managed Git repository, providing
built-in versioning, traceability, and deduplication.
*/
package svc

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/inovacc/unravel-oss/pkg/knowledge/chunks"
)

// KSService defines the business logic for managing Knowledge Sources.
// It coordinates between the filesystem (Git) and the metadata catalog (Postgres).
type KSService struct {
	db      *sql.DB
	kbStore string // root path to the versioned application captures
}

// NewKSService creates a new service instance.
func NewKSService(db *sql.DB, kbStorePath string) *KSService {
	return &KSService{
		db:      db,
		kbStore: kbStorePath,
	}
}

// CaptureOptions defines the configuration for a new KS capture pass.
type CaptureOptions struct {
	AppSlug string
	Version string
	Source  string // e.g. "npm install ...", "git clone ...", or directory path
	Author  string
	Message string // commit message for the version
}

// Result describes the outcome of a capture.
type Result struct {
	AppKBID string
	Epoch   int
	Commit  string // Git commit hash
	Path    string // Local path to the versioned source
}

// Capture performs an end-to-end capture, versioning the source using Git.
// Fulfills the "semantically best approach to store code" by treating KS as
// version-controlled entities.
func (s *KSService) Capture(ctx context.Context, opts CaptureOptions) (*Result, error) {
	// 1. Resolve App KBID
	appID, err := s.resolveAppID(opts.AppSlug)
	if err != nil {
		return nil, fmt.Errorf("resolve app id: %w", err)
	}

	// 2. Prepare storage directory
	repoPath := filepath.Join(s.kbStore, appID, "repo")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir repo: %w", err)
	}

	// 3. Initialize Git repo if it doesn't exist (D-39-SOKS)
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); os.IsNotExist(err) {
		if err := s.runGit(repoPath, "init", "--initial-branch=main"); err != nil {
			return nil, fmt.Errorf("git init: %w", err)
		}
		// Add .gitignore for Unravel internal files
		_ = os.WriteFile(filepath.Join(repoPath, ".gitignore"), []byte("knowledge.json\n_score.json\nSCORECARD.md\n"), 0o644)
	}

	// 4. Staging area for the new version
	tmpDir, err := os.MkdirTemp("", "unravel-ks-capture-*")
	if err != nil {
		return nil, fmt.Errorf("mkdir temp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// 5. [Placeholder] Ingest logic would go here — copying files to repoPath
	// For this prototype, we assume files are already in repoPath or being moved there.

	// 6. Commit the new version
	if err := s.runGit(repoPath, "add", "."); err != nil {
		return nil, fmt.Errorf("git add: %w", err)
	}

	// Check if there are changes to commit
	if err := s.runGit(repoPath, "diff", "--cached", "--quiet"); err != nil {
		// Changes exist
		msg := opts.Message
		if msg == "" {
			msg = fmt.Sprintf("Capture version %s from %s", opts.Version, opts.Source)
		}

		if err := s.runGit(repoPath, "commit", "-m", msg, "--author", fmt.Sprintf("%s <unravel@local>", opts.Author)); err != nil {
			return nil, fmt.Errorf("git commit: %w", err)
		}
	}

	// 7. Get commit hash
	commit, err := s.getHeadHash(repoPath)
	if err != nil {
		return nil, fmt.Errorf("get commit hash: %w", err)
	}

	// 8. Record in DB (Phase 21-SOKS)
	sourceID, epoch, err := s.recordKSEpoch(opts.AppSlug, opts.Version, commit, opts.Source)
	if err != nil {
		return nil, fmt.Errorf("record epoch: %w", err)
	}

	// 9. Record Manifest (Phase 21-SOKS-SYNC)
	if err := s.recordManifest(ctx, sourceID, opts.AppSlug, repoPath); err != nil {
		return nil, fmt.Errorf("record manifest: %w", err)
	}

	return &Result{
		AppKBID: appID,
		Epoch:   epoch,
		Commit:  commit,
		Path:    repoPath,
	}, nil
}

func (s *KSService) runGit(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git %v: %w (output: %s)", args, err, string(out))
	}
	return nil
}

func (s *KSService) getHeadHash(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out[:len(out)-1]), nil
}

func (s *KSService) recordManifest(ctx context.Context, sourceID int64, slug, repoPath string) error {
	now := time.Now().UnixMilli()
	chunker := chunks.New()

	return filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.Contains(path, ".git") {
			return err
		}

		relPath, _ := filepath.Rel(repoPath, path)
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		h := sha256.Sum256(body)
		sha := hex.EncodeToString(h[:])

		// 1. Record body
		_, _ = s.db.ExecContext(ctx, `
			INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
			VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			sha, body, len(body), now)

		// 2. Record file
		_, _ = s.db.ExecContext(ctx, `
			INSERT INTO files (file_sha256, file_size, first_seen_at)
			VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			sha, len(body), now)

		// 3. Upsert module to get ID
		var moduleID int64
		excerpt := string(body[:min(len(body), 200)])
		excerpt = strings.Map(func(r rune) rune {
			if r == 0 || r == utf8.RuneError {
				return -1
			}
			return r
		}, excerpt)

		err = s.db.QueryRowContext(ctx, `
			INSERT INTO modules (app, name, body_sha256, body_size, body_excerpt, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $6)
			ON CONFLICT (app, body_sha256) DO UPDATE SET last_seen_at = $6
			RETURNING id`,
			slug, relPath, sha, len(body), excerpt, now).Scan(&moduleID)
		if err != nil {
			return fmt.Errorf("upsert module %s: %w", relPath, err)
		}

		// 4. Record ref
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO file_app_refs (file_sha256, source_id, rel_path, observed_at)
			VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			sha, sourceID, relPath, now)
		if err != nil {
			return err
		}

		// 5. Semantic Chunking (D-40)
		if utf8.Valid(body) {
			fileChunks := chunker.ChunkFile(relPath, body)
			for i, c := range fileChunks {
				content := c.Content
				content = strings.ReplaceAll(content, "\x00", "")
				if !utf8.ValidString(content) {
					content = strings.ToValidUTF8(content, "")
				}
				title := c.Title
				title = strings.ReplaceAll(title, "\x00", "")
				if !utf8.ValidString(title) {
					title = strings.ToValidUTF8(title, "")
				}
				_, err = s.db.ExecContext(ctx, `
					INSERT INTO module_chunks (module_id, title, content, has_code, chunk_index, created_at)
					VALUES ($1, $2, $3, $4, $5, $6)`,
					moduleID, title, content, c.HasCode, i, now)
				if err != nil {
					return fmt.Errorf("insert chunk: %w", err)
				}
			}
		}

		return nil
	})
}

func (s *KSService) resolveAppID(slug string) (string, error) {
	// D-35-STABLE-IDENTITY: kb_id is sha256(name|platform)
	platform := "npm" // default for this flow
	if filepath.IsAbs(slug) || slug == "gemini-cli-repo" {
		platform = "source"
	}

	h := sha256.New()
	h.Write([]byte(slug))
	h.Write([]byte("|"))
	h.Write([]byte(platform))
	kbID := hex.EncodeToString(h.Sum(nil))[:16] // use first 16 chars for the directory id

	// Query kb_apps table
	var id string
	err := s.db.QueryRow(`SELECT kb_id FROM kb_apps WHERE kb_id = $1`, kbID).Scan(&id)
	if err == sql.ErrNoRows {
		now := time.Now().UnixMilli()
		_, err = s.db.Exec(`
			INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			kbID, slug, slug, platform, now, now)
		return kbID, err
	}
	return id, err
}

func (s *KSService) recordKSEpoch(slug, version, commit, source string) (int64, int, error) {
	// 1. Get next epoch
	var nextEpoch int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(epoch), 0) + 1 FROM knowledge_sources WHERE app = $1`, slug).Scan(&nextEpoch)
	if err != nil {
		return 0, 0, fmt.Errorf("get next epoch: %w", err)
	}

	// 2. Insert record
	var id int64
	now := time.Now().UnixMilli()
	err = s.db.QueryRow(`
		INSERT INTO knowledge_sources (app, epoch, source_path, source_kind, app_version, commit_hash, captured_at)
		VALUES ($1, $2, $3, 'git-managed', $4, $5, $6)
		RETURNING id`,
		slug, nextEpoch, source, version, commit, now).Scan(&id)
	if err != nil {
		return 0, 0, fmt.Errorf("insert knowledge_source: %w", err)
	}

	return id, nextEpoch, nil
}

// IsDirty checks if there are uncommitted changes in the app's KS repository.
func (s *KSService) IsDirty(slug string) (bool, error) {
	path, err := s.RepoPath(slug)
	if err != nil {
		return false, err
	}

	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = path
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}

	return len(strings.TrimSpace(string(out))) > 0, nil
}

// Sync ensures the local KS repository matches the latest epoch in the database.
// If the repo is missing, it is initialized and reconstructed from module_bodies.
// If local changes exist, they are committed as a "checkpoint" before reconstruction.
func (s *KSService) Sync(ctx context.Context, slug string) error {
	// 1. Get latest epoch metadata from DB
	var sourceID int64
	var epoch int
	var commit string
	var version string
	err := s.db.QueryRow(`
		SELECT id, epoch, commit_hash, app_version FROM knowledge_sources
		WHERE app = $1 ORDER BY epoch DESC LIMIT 1`, slug).Scan(&sourceID, &epoch, &commit, &version)
	if err == sql.ErrNoRows {
		return fmt.Errorf("no epochs found in DB for app %q", slug)
	}
	if err != nil {
		return err
	}

	// 2. Prepare local repo
	repoPath, err := s.RepoPath(slug)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		return err
	}

	// 3. Init Git if needed
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); os.IsNotExist(err) {
		if err := s.runGit(repoPath, "init", "--initial-branch=main"); err != nil {
			return err
		}
	}

	// 4. Resolve local changes (Phase 21-SOKS-RESOLVE)
	dirty, err := s.IsDirty(slug)
	if err != nil {
		return fmt.Errorf("check dirty state: %w", err)
	}
	if dirty {
		if err := s.runGit(repoPath, "add", "."); err != nil {
			return err
		}
		msg := "Auto-checkpoint before sync"
		if err := s.runGit(repoPath, "commit", "-m", msg, "--author", "Unravel <unravel@local>"); err != nil {
			// Ignore commit failures (e.g. only untracked files that git add handled)
		}
	}

	// 5. Check if we already have this commit
	localHead, _ := s.getHeadHash(repoPath)
	if localHead == commit {
		return nil // Already in sync
	}

	// 5. Reconstruct from DB manifest
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.rel_path, b.body FROM file_app_refs r
		JOIN module_bodies b ON b.body_sha256 = r.file_sha256
		WHERE r.source_id = $1`, sourceID)
	if err != nil {
		return fmt.Errorf("query manifest: %w", err)
	}
	defer rows.Close()

	// Clear current working tree (except .git)
	entries, _ := os.ReadDir(repoPath)
	for _, e := range entries {
		if e.Name() == ".git" {
			continue
		}
		_ = os.RemoveAll(filepath.Join(repoPath, e.Name()))
	}

	count := 0
	for rows.Next() {
		var relPath string
		var body []byte
		if err := rows.Scan(&relPath, &body); err != nil {
			return err
		}

		fullPath := filepath.Join(repoPath, relPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(fullPath, body, 0o644); err != nil {
			return err
		}
		count++
	}

	if count == 0 {
		return fmt.Errorf("zero files found in DB manifest for epoch %d", epoch)
	}

	// 6. Finalize local Git state
	if err := s.runGit(repoPath, "add", "."); err != nil {
		return err
	}

	msg := fmt.Sprintf("Synchronized Epoch %d (%s) from Knowledge Base", epoch, version)
	if err := s.runGit(repoPath, "commit", "-m", msg, "--author", "Unravel <unravel@local>"); err != nil {
		// If the commit failed (e.g. no changes), it might still be ok
	}

	return nil
}

// RepoPath returns the physical filesystem path for an app's Git repository.
func (s *KSService) RepoPath(slug string) (string, error) {
	appID, err := s.resolveAppID(slug)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.kbStore, appID, "repo"), nil
}

// Status returns the current Git status of the app's KS repository.
func (s *KSService) Status(slug string) (string, error) {
	path, err := s.RepoPath(slug)
	if err != nil {
		return "", err
	}

	cmd := exec.Command("git", "status", "--short")
	cmd.Dir = path
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git status: %w (output: %s)", err, string(out))
	}
	return string(out), nil
}

// Log returns the Git commit history for the app's KS repository.
func (s *KSService) Log(slug string) (string, error) {
	path, err := s.RepoPath(slug)
	if err != nil {
		return "", err
	}

	cmd := exec.Command("git", "log", "--oneline", "--decorate")
	cmd.Dir = path
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git log: %w (output: %s)", err, string(out))
	}
	return string(out), nil
}

// Checkout switches the app's KS repository to a specific commit or epoch ref.
func (s *KSService) Checkout(slug, ref string) error {
	path, err := s.RepoPath(slug)
	if err != nil {
		return err
	}

	if err := s.runGit(path, checkoutArgs(ref)...); err != nil {
		return fmt.Errorf("git checkout %q: %w", ref, err)
	}
	return nil
}

// checkoutArgs builds the argv for `git checkout --end-of-options <ref> --`.
// "--end-of-options" (git >= 2.24) stops flag parsing, so a ref beginning with
// "-" (e.g. "--orphan" / "--detach") is treated as a checkout target, not a
// flag (finding #10). A trailing "--" ALONE is insufficient: it only separates
// pathspecs that come AFTER it and leaves a dash-leading ref parseable as an
// option (verified: `git checkout --detach --` detaches HEAD, whereas
// `git checkout --end-of-options --detach --` rejects it as an invalid ref).
// The trailing "--" is kept to also disambiguate the ref from a same-named path.
func checkoutArgs(ref string) []string {
	return []string{"checkout", "--end-of-options", ref, "--"}
}

// Grep performs an ultra-fast full-text search over the app's code repository.
// Fulfills the "semantically best FTS" by using Git's optimized indexing.
func (s *KSService) Grep(slug, pattern string) (string, error) {
	path, err := s.RepoPath(slug)
	if err != nil {
		return "", err
	}

	// git grep -n -I --color=always -e <pattern> --
	cmd := exec.Command("git", grepArgs(pattern)...)
	cmd.Dir = path
	out, err := cmd.CombinedOutput()
	if err != nil {
		// git grep returns 1 if no matches found
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "", nil
		}
		return "", fmt.Errorf("git grep: %w (output: %s)", err, string(out))
	}
	return string(out), nil
}

// grepArgs builds the argv for `git grep ... -e <pattern> --`. Passing the
// pattern as the value of -e (rather than a trailing positional) plus the
// trailing "--" end-of-options marker neutralizes argument injection: a
// pattern starting with "-" (e.g. the known --open-files-in-pager RCE
// vector) becomes a literal search pattern, never a parsed flag (finding
// #10).
func grepArgs(pattern string) []string {
	return []string{"grep", "-n", "-I", "--color=always", "-e", pattern, "--"}
}

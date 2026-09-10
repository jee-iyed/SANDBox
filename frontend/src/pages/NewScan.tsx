import { useRef, useState } from 'react';
import type { DragEvent } from 'react';
import { useNavigate } from 'react-router-dom';

import { api, friendlyError } from '../api/client';
import { Alert } from '../components/Alert';
import { formatBytes } from '../utils/format';

export function NewScan() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const acceptFile = (candidate: File | undefined | null) => {
    if (!candidate) {
      return;
    }
    setFile(candidate);
    setError(null);
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    acceptFile(event.dataTransfer.files?.[0]);
  };

  const clearFile = () => {
    setFile(null);
    setError(null);
    if (inputRef.current) {
      inputRef.current.value = '';
    }
  };

  const submit = async () => {
    if (!file || uploading) {
      return;
    }
    setUploading(true);
    setError(null);
    try {
      const scan = await api.createScan(file);
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(friendlyError(err));
      setUploading(false);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Open Securely</h1>
          <p className="page-subtitle">Send an attachment through SANDBox before it can be accessed.</p>
        </div>
      </div>

      <section className="panel">
        <div className="panel-body">
          <div
            role="button"
            tabIndex={0}
            aria-label={`Upload area${file ? ', file selected' : ''}`}
            className={`dropzone${dragging ? ' dropzone-drag' : ''}${file ? ' dropzone-has-file' : ''}`}
            onClick={() => inputRef.current?.click()}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                inputRef.current?.click();
              }
            }}
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
          >
            <input
              ref={inputRef}
              type="file"
              className="visually-hidden"
              data-testid="file-input"
              onChange={(event) => acceptFile(event.target.files?.[0])}
            />
            <div className="dropzone-icon" aria-hidden="true">
              ⇑
            </div>
            <p className="dropzone-primary">Drag &amp; drop a file here</p>
            <p className="dropzone-secondary">or</p>
            <button type="button" className="btn btn-secondary" onClick={() => inputRef.current?.click()}>
              Choose File
            </button>
          </div>

          {file && (
            <div className="selected-file">
              <div>
                <span className="selected-file-name">{file.name}</span>
                <span className="selected-file-meta">Size: {formatBytes(file.size)}</span>
              </div>
              <button type="button" className="btn btn-ghost btn-sm" onClick={clearFile}>
                Remove
              </button>
            </div>
          )}

          {error && <Alert variant="error">{error}</Alert>}

          <div className="form-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!file || uploading}
              onClick={() => void submit()}
            >
              {uploading ? 'Queuing secure analysis…' : 'Open Securely'}
            </button>
          </div>

          <p className="page-note">
            The original attachment remains controlled until the backend completes M1–M5, QR analysis,
            and the deterministic risk decision.
          </p>
        </div>
      </section>
    </div>
  );
}

import type { IdentityDocument } from '../types';

interface Props {
  documents: IdentityDocument[];
  onAddDocument: () => void;
  onSelectDocument: (id: string) => void;
}

const DOC_TYPE_LABELS: Record<string, string> = {
  passport: 'Passport',
  driving_licence: 'Driving Licence',
  national_id: 'National ID',
  birth_certificate: 'Birth Certificate',
};

function docTypeLabel(documentType: string): string {
  return DOC_TYPE_LABELS[documentType] ?? documentType;
}

function docTypeIcon(documentType: string): string {
  switch (documentType) {
    case 'passport':
      return 'PP';
    case 'driving_licence':
      return 'DL';
    case 'national_id':
      return 'ID';
    case 'birth_certificate':
      return 'BC';
    default:
      return 'ID';
  }
}

function maskDocumentNumber(documentNumber: string): string {
  if (documentNumber.length <= 4) return documentNumber;
  return '•••• ' + documentNumber.slice(-4);
}

export function MyDocuments({ documents, onAddDocument, onSelectDocument }: Props) {
  if (documents.length === 0) {
    return (
      <div className="fade-in">
        <div className="card section" style={{ textAlign: 'center', padding: 32 }}>
          <div style={{ fontSize: '2.5rem', marginBottom: 12, color: 'var(--text-muted)' }}>ID</div>
          <h2 style={{ marginBottom: 8 }}>No documents yet</h2>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 20, fontSize: '0.9rem' }}>
            Add your identity documents here. When you visit a verifier, they'll confirm what you've entered.
          </p>
          <button className="btn btn-primary" onClick={onAddDocument}>
            Add a document
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="fade-in">
      <div className="section">
        <div className="section-title">My Documents</div>
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          {documents.map((doc, i) => (
            <button
              key={doc.id}
              onClick={() => onSelectDocument(doc.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                width: '100%',
                padding: '14px 16px',
                background: 'none',
                border: 'none',
                borderBottom: i < documents.length - 1 ? '1px solid var(--border)' : 'none',
                cursor: 'pointer',
                textAlign: 'left',
                color: 'var(--text-primary)',
              }}
            >
              {/* Icon */}
              <div
                style={{
                  width: 40,
                  height: 40,
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--surface-2, var(--border))',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  color: 'var(--text-muted)',
                  letterSpacing: '0.05em',
                  flexShrink: 0,
                }}
              >
                {docTypeIcon(doc.documentType)}
              </div>

              {/* Details */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, marginBottom: 2 }}>
                  {docTypeLabel(doc.documentType)}
                </div>
                <div
                  style={{
                    fontSize: '0.85rem',
                    color: 'var(--text-secondary)',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {doc.fullName}
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 1 }}>
                  {maskDocumentNumber(doc.documentNumber)}
                </div>
              </div>

              {/* Country */}
              <div
                style={{
                  fontSize: '0.85rem',
                  color: 'var(--text-muted)',
                  flexShrink: 0,
                }}
              >
                {doc.country}
              </div>

              {/* Chevron */}
              <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', flexShrink: 0 }}>›</div>
            </button>
          ))}
        </div>
      </div>

      <div className="section">
        <button className="btn btn-secondary" onClick={onAddDocument}>
          Add another document
        </button>
      </div>
    </div>
  );
}

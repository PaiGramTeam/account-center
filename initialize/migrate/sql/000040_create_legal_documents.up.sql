CREATE TABLE IF NOT EXISTS legal_documents (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    document_type VARCHAR(32) NOT NULL,
    version VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    content LONGTEXT NOT NULL,
    published BOOLEAN NOT NULL DEFAULT FALSE,
    published_at DATETIME(3) NULL,
    updated_by BIGINT UNSIGNED NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    UNIQUE KEY uk_legal_document_type_version (document_type, version),
    KEY idx_legal_documents_published (published),
    KEY idx_legal_documents_updated_by (updated_by),
    KEY idx_legal_documents_deleted_at (deleted_at),
    CONSTRAINT fk_legal_documents_updated_by FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

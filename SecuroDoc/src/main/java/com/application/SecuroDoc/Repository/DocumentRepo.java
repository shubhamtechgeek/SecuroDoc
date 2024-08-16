package com.application.SecuroDoc.Repository;

import com.application.SecuroDoc.DTO.api.IDocument;
import com.application.SecuroDoc.Entity.DocumentEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

import static com.application.SecuroDoc.Constant.Constants.*;

@Repository
public interface DocumentRepo extends JpaRepository<DocumentEntity, Long> {

    @Query(countQuery = COUNT_QUERY, value = QUERY_DOCUMENTS, nativeQuery = true)
    Page<IDocument> findDocuments(Pageable pageable);

    @Query(countQuery = COUNT_QUERY_BY_NAME, value = QUERY_DOCUMENTS_BY_NAME, nativeQuery = true)
    Page<IDocument> findDocumentsByName(@Param("documentName") String name, Pageable pageable);

    @Query(value = QUERY_DOCUMENT, nativeQuery = true)
    Optional<IDocument> findDocumentByDocumentId(String documentId);

    Optional<DocumentEntity> findByDocumentId(String documentId);
}

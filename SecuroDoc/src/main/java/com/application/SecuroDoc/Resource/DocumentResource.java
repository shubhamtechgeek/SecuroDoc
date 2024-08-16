package com.application.SecuroDoc.Resource;


import com.application.SecuroDoc.DTO.UpdateDocRequest;
import com.application.SecuroDoc.DTO.User;
import com.application.SecuroDoc.Domain.Response;
import com.application.SecuroDoc.Service.DocumentService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import static com.application.SecuroDoc.Utils.RequestUtils.getResponse;
import static java.net.URI.create;
import static java.util.Map.of;
import static org.springframework.http.HttpHeaders.CONTENT_DISPOSITION;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;

@RestController
@RequiredArgsConstructor
@RequestMapping(path = { "/documents" })
public class DocumentResource {
    private final DocumentService documentService;

    @PostMapping("/upload")
    @PreAuthorize("hasAnyAuthority('document:create') or hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> saveDocuments(@AuthenticationPrincipal User user, @RequestParam("files") List<MultipartFile> documents, HttpServletRequest request) {
        var newDocuments = documentService.saveDocuments(user.getUserId(), documents);
        return ResponseEntity.created(create("")).body(getResponse(request, of("documents", newDocuments), "Document(s) uploaded", CREATED));
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('document:read') or hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> getDocuments(@AuthenticationPrincipal User user, HttpServletRequest request,
                                                 @RequestParam(value = "page", defaultValue = "0") int page,
                                                 @RequestParam(value = "size", defaultValue = "5") int size) {
        var documents = documentService.getDocuments(page, size);
        return ResponseEntity.ok(getResponse(request, of("documents", documents), "Document(s) retrieved", OK));
    }

    @GetMapping("/search")
    @PreAuthorize("hasAnyAuthority('document:read') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> searchDocuments(@AuthenticationPrincipal User user, HttpServletRequest request,
                                                    @RequestParam(value = "page", defaultValue = "0") int page,
                                                    @RequestParam(value = "size", defaultValue = "5") int size,
                                                    @RequestParam(value = "name", defaultValue = "") String name) {
        var documents = documentService.getDocuments(page, size, name);
        return ResponseEntity.ok(getResponse(request, of("documents", documents), "Document(s) retrieved", OK));
    }

    @GetMapping("/{documentId}")
    @PreAuthorize("hasAnyAuthority('document:read') or hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> getDocument(@AuthenticationPrincipal User user, @PathVariable("documentId") String documentId, HttpServletRequest request) {
        var document = documentService.getDocumentByDocumentId(documentId);
        return ResponseEntity.ok(getResponse(request, of("document", document), "Document retrieved", OK));
    }

    @PatchMapping()
    @PreAuthorize("hasAnyAuthority('document:update') or hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> updateDocument(@AuthenticationPrincipal User user, @RequestBody UpdateDocRequest document, HttpServletRequest request) {
        var updateDocument = documentService.updateDocument(document.getDocumentId(), document.getName(), document.getDescription());
        return ResponseEntity.ok(getResponse(request, of("document", updateDocument), "Document updated", OK));
    }

    @GetMapping("/download/{documentName}")
    @PreAuthorize("hasAnyAuthority('document:read') or hasAnyRole('USER' , 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Resource> downloadDocument(@AuthenticationPrincipal User user, @PathVariable("documentName") String documentName) throws IOException {
        var resource = documentService.getResource(documentName);
        var httpHeaders = new HttpHeaders();
        httpHeaders.add("File-Name", documentName);
        httpHeaders.add(CONTENT_DISPOSITION, String.format("attachment;File-Name=%s", resource.getFilename()));
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(Files.probeContentType(resource.getFile().toPath())))
                .headers(httpHeaders).body(resource);
    }

}

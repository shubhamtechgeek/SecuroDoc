package com.application.SecuroDoc.Entity;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.persistence.*;
import lombok.*;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;
import static jakarta.persistence.FetchType.LAZY;


@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "documents")
@JsonInclude(NON_DEFAULT)
public class DocumentEntity extends Auditable {
    @Column(updatable = false, unique = true, nullable = false)
    private String documentId;
    private String name;
    private String description;
    private String uri;
    private long size;
    private String formattedSize;
    private String icon;
    private String extension;
    @ManyToOne(fetch = LAZY)
    @JoinColumn(
            name = "user_id",
            referencedColumnName = "id",
            foreignKey = @ForeignKey(name = "fk_documents_owner", foreignKeyDefinition = "foreign key /* FK */ (user_id) references users", value = ConstraintMode.CONSTRAINT)
    )
    private UserEntity owner;
}


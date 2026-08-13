
package com.forensics.entity;
import jakarta.persistence.*;
@Entity
public class EmailReport{
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY)
 private Long id;
 private String sender;
 private String subject;
}

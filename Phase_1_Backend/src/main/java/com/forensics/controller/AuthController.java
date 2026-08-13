
package com.forensics.controller;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/auth")
public class AuthController{
 @PostMapping("/register")
 public String register(){ return "Register endpoint"; }
 @PostMapping("/login")
 public String login(){ return "Login endpoint"; }
}

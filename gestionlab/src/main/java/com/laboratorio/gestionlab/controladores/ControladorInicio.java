package com.laboratorio.gestionlab.controladores;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ControladorInicio {

    @GetMapping("/")
    public String home() {
        return "redirect:/index";
    }

    @GetMapping("/error")
    public String Error(){
        return "error";
    }

    @GetMapping("/index")
    public String Index(@AuthenticationPrincipal OidcUser principal, Model model){
        if (principal != null) {
            model.addAttribute("username", principal.getPreferredUsername());
            model.addAttribute("email", principal.getEmail());
        }
        return "index";
    }

}

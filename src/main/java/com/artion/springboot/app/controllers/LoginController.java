package com.artion.springboot.app.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,@RequestParam(value = "logout", required = false) String logout, Model model, Principal principal, RedirectAttributes flash){

        // Ha habido un inicio de seccion previamente?
        if (principal != null){
            flash.addFlashAttribute("info", "Ya ha iniciado sesión anteriormente");
            return "redirect:/";
        }

        if (error != null){
            model.addAttribute("error", "Error en el login: Nombre de usuario o contraseña incorrecta, por favor vuelva a intentarlo!");
        }

        if (logout != null){
            model.addAttribute("success", "Se ha cerrado la sesión correctamente!");
        }

        return "login";
    }
}

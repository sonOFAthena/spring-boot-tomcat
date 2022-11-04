package com.artion.springboot.app.controllers;

import com.artion.springboot.app.models.service.IClienteService;
import com.artion.springboot.app.view.xml.ClienteList;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/clientes")
public class ClienteRestController {

    @Autowired
    private IClienteService clienteService;

    @GetMapping(value="/listar")
//    @Secured("ROLE_ADMIN")
    public ClienteList listar(){
        return new ClienteList(clienteService.findAll());
    }
}

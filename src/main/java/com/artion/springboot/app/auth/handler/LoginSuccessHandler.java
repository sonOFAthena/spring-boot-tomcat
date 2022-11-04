package com.artion.springboot.app.auth.handler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.FlashMap;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.support.SessionFlashMapManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;

@Component
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private LocaleResolver localeResolver;

    @Autowired
    private MessageSource messageSource;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //Obtener los mensajes flash en un Map, es similar a usar el RedirectAtributes con flash que se usa en el controlador
        SessionFlashMapManager flashMapManager = new SessionFlashMapManager();
        FlashMap flashMap = new FlashMap();


        Locale locale = localeResolver.resolveLocale(request);

        String mensaje = String.format(messageSource.getMessage("text.login.success", null, locale), authentication.getName());

        flashMap.put("success", mensaje);
        flashMapManager.saveOutputFlashMap(flashMap, request, response);

        if (authentication != null){
            logger.info(mensaje);
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }
}

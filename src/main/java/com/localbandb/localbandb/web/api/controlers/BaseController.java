package com.localbandb.localbandb.web.api.controlers;

import org.springframework.web.servlet.ModelAndView;

public abstract class BaseController {
  protected ModelAndView view(String view, ModelAndView modelAndView) {
    modelAndView.setViewName(view);
    return modelAndView;
  }

  protected  ModelAndView view(String view) {
    return this.view(view, new ModelAndView());
  }

  protected ModelAndView redirect(String url) {
    return this.redirect(url, new ModelAndView());
  }

  protected ModelAndView redirect(String url, ModelAndView modelAndView) {
    modelAndView.setViewName("redirect:/" + url);
    return modelAndView;
  }
}

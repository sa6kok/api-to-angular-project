package com.localbandb.localbandb.web.api.controlers;

import com.localbandb.localbandb.services.services.CountryService;
import com.localbandb.localbandb.services.services.PropertyService;
import com.localbandb.localbandb.web.api.models.PictureAddModel;
import com.localbandb.localbandb.web.api.models.PropertyCreateModel;
import com.localbandb.localbandb.web.api.models.PropertyViewModel;
import javassist.NotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600)
@RestController
@RequestMapping("/property")
public class PropertyController extends BaseController {
    private final PropertyService propertyService;

    @Autowired
    public PropertyController( PropertyService propertyService ) {
        this.propertyService = propertyService;
    }


    @PostMapping(value = "/create")
    @Secured("ROLE_HOST")
    public boolean postCreateProperty(@RequestBody PropertyCreateModel model) throws NotFoundException {
     return propertyService.save(model);
    }

    @GetMapping("/my")
    @Secured("ROLE_HOST")
    public List<PropertyViewModel> getMyProperties() {
        return propertyService.getMyProperties();
    }


    @GetMapping("/details/{id}")
    public PropertyViewModel findById(@PathVariable String id) throws NotFoundException {
       return  propertyService.findById(id);
    }

    @PostMapping("/picture/add")
    @Secured("ROLE_HOST")
    public boolean addPictureToProperty(@RequestBody PictureAddModel pictureAddModel) {
        return propertyService.addPictureToProperty(pictureAddModel.getPropertyId(), pictureAddModel.getPictureUrl());
    }
}

package com.localbandb.localbandb.web.api.controlers;

import com.localbandb.localbandb.services.services.CityService;
import com.localbandb.localbandb.services.services.CountryService;
import com.localbandb.localbandb.services.services.UserService;
import com.localbandb.localbandb.web.api.models.CityAddModel;
import com.localbandb.localbandb.web.api.models.CountryAddModel;
import com.localbandb.localbandb.web.api.models.UserViewModel;
import javassist.NotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600)
@RestController
@RequestMapping("/admin")
public class AdminController extends BaseController {
    private final UserService userService;
    private final CountryService countryService;
    private final CityService cityService;

    @Autowired
    public AdminController(UserService userService, CountryService countryService, CityService cityService) {
        this.userService = userService;
        this.countryService = countryService;
        this.cityService = cityService;
    }

    @GetMapping("/users")
    @Secured("ROLE_ADMIN")
    public List<UserViewModel> home() {
       return userService.findAllUsersWithoutTheLoggedIn();
    }

    @GetMapping("/status/{id}")
    @Secured("ROLE_ADMIN")
    public boolean statusChange(@PathVariable String id) throws NotFoundException {
        return userService.changeUserStatus(id);
    }

    @PostMapping("/city/add")
    @Secured("ROLE_ADMIN")
    public boolean addCity(@RequestBody CityAddModel model) throws NotFoundException {
        return cityService.addCity(model.getCountry(),model.getCity());
    }

    @PostMapping("country/add")
    @Secured("ROLE_ADMIN")
    public boolean addCountry(@RequestBody CountryAddModel model) {
        return countryService.addCountry(model.getCountry());
    }
}

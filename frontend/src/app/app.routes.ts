import { Routes } from "@angular/router";
import { AppComponent } from "./app.component";

export const routes: Routes = [
  {
    path: "",
    loadComponent: () =>
      import("./home/home.component").then((m) => m.HomeComponent),
  },
  {
    path: "user/:id",
    loadComponent: () =>
      import("./user-profile/user-profile.component").then(
        (m) => m.UserProfileComponent
      ),
  },
];


import { Component, OnInit } from "@angular/core";
import { CommonModule } from "@angular/common";
import { ActivatedRoute, Router } from "@angular/router";
import { HttpClient, HttpErrorResponse } from "@angular/common/http";

interface UserData {
  id: number;
  username: string;
  email: string;
  password?: string;
  role: string;
  is_vulnerable: boolean;
  access_granted: boolean;
  message: string;
}

@Component({
  selector: "app-user-profile",
  standalone: true,
  imports: [CommonModule],
  templateUrl: "./user-profile.component.html",
  styleUrls: ["./user-profile.component.css"],
})
export class UserProfileComponent implements OnInit {
  apiUrl = "http://localhost:8000";
  userId: number = 0;
  userData: UserData | null = null;
  loading: boolean = true;
  error: string = "";
  currentUser: any = null;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private http: HttpClient
  ) {}

  ngOnInit() {
    const token = localStorage.getItem("auth_token");
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        this.currentUser = {
          user_id: payload.user_id,
          username: payload.username,
          role: payload.role,
        };
      } catch (e) {
        console.error("Error decoding token", e);
      }
    }

    this.route.params.subscribe((params) => {
      this.userId = +params["id"];
      this.fetchUserData();
    });
  }

  fetchUserData() {
    this.loading = true;
    this.error = "";

    this.http
      .get<UserData>(`${this.apiUrl}/api/user/${this.userId}`)
      .subscribe({
        next: (response) => {
          this.userData = response;
          this.loading = false;
          console.log("User data fetched:", response);
        },
        error: (error: HttpErrorResponse) => {
          this.loading = false;
          if (error.status === 401) {
            this.error =
              "401 Unauthorized: " +
              (error.error.detail || "Invalid or missing token");
          } else if (error.status === 403) {
            this.error =
              "403 Forbidden: " + (error.error.detail || "Access denied");
          } else if (error.status === 404) {
            this.error = "404 Not Found: User not found";
          } else {
            this.error =
              "Error fetching user data: " +
              (error.error.detail || error.message);
          }
          console.error("Error fetching user data:", error);
        },
      });
  }

  goBack() {
    this.router.navigate(["/"]);
  }
}

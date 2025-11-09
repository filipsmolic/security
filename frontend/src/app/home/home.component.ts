import { Component } from "@angular/core";
import { CommonModule } from "@angular/common";
import { FormsModule } from "@angular/forms";
import { Router } from "@angular/router";
import { HttpClient } from "@angular/common/http";
import { environment } from "../../environments/environment";

interface SQLInjectionResponse {
  results: any[];
  query_executed: string;
  is_vulnerable: boolean;
  warning?: string;
}

@Component({
  selector: "app-home",
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: "./home.component.html",
  styleUrls: ["./home.component.css"],
})
export class HomeComponent {
  apiUrl = environment.apiUrl;

  searchQuery: string = "";
  vulnerableModeSQL: boolean = false;
  searchResults: any[] = [];
  queryExecuted: string = "";
  isVulnerable: boolean = false;
  warningMessage: string = "";
  showResults: boolean = false;

  vulnerableModeAccess: boolean = false;

  authToken: string = "";
  currentUser: any = null;

  ngOnInit() {
    this.vulnerableModeSQL = localStorage.getItem("vulnerableSQL") === "true";
    this.vulnerableModeAccess =
      localStorage.getItem("vulnerableAccess") === "true";

    this.login();
  }

  login() {
    console.log("Attempting to fetch JWT token...");
    this.http.get(`${this.apiUrl}/api/auth/login`).subscribe({
      next: (response: any) => {
        this.authToken = response.access_token;
        this.currentUser = response.user;
        localStorage.setItem("auth_token", this.authToken);
      },
      error: (error) => {
        console.error("Authentication failed:", error);
      },
    });
  }

  sqlInjectionExamples = [
    {
      name: "Izvuci sve korisnike",
      query: "' OR '1'='1",
    },
    {
      name: "UNION - dohvati lozinke",
      query: "' UNION SELECT username, password FROM users--",
    },
    {
      name: "UNION - druga tablica",
      query: "' UNION SELECT name, description FROM products--",
    },
  ];

  constructor(private http: HttpClient, private router: Router) {}

  updateVulnerabilitySettings() {
    const settings = {
      sql_injection: this.vulnerableModeSQL,
      access_control: this.vulnerableModeAccess,
    };

    this.http
      .post(`${this.apiUrl}/api/toggle-vulnerabilities`, settings)
      .subscribe({
        next: () => console.log("Vulnerability settings updated"),
        error: (error) => console.error("Error updating settings:", error),
      });
  }

  searchUsers() {
    this.updateVulnerabilitySettings();

    const requestBody = {
      search_query: this.searchQuery,
      vulnerable_mode: this.vulnerableModeSQL,
    };

    this.http
      .post<SQLInjectionResponse>(
        `${this.apiUrl}/api/sql-injection/search`,
        requestBody
      )
      .subscribe({
        next: (response) => {
          this.searchResults = response.results;
          this.queryExecuted = response.query_executed;
          this.isVulnerable = response.is_vulnerable;
          this.warningMessage = response.warning || "";
          this.showResults = true;
        },
        error: (error) => {
          console.error("Error:", error);
          this.searchResults = [];
          this.warningMessage = "Greška pri pretrazi!";
          this.showResults = true;
        },
      });
  }

  setExample(example: any) {
    this.searchQuery = example.query;
    this.vulnerableModeSQL = true;
  }

  toggleAccessControl() {
    localStorage.setItem(
      "vulnerableAccess",
      this.vulnerableModeAccess.toString()
    );
    this.updateVulnerabilitySettings();
  }

  toggleSQL() {
    localStorage.setItem("vulnerableSQL", this.vulnerableModeSQL.toString());
  }

  getColumns(): string[] {
    if (this.searchResults.length === 0) return [];
    return Object.keys(this.searchResults[0]);
  }

  openUserProfile(userId: number) {
    this.router.navigate(["/user", userId]);
  }

  openAdminPanel() {
    const token = localStorage.getItem("auth_token");
    const vulnerable = this.vulnerableModeAccess ? "true" : "false";

    let url = `${this.apiUrl}/api/admin/users?vulnerable=${vulnerable}`;

    if (token) {
      this.fetchAndOpenInNewTab(url, token);
    } else {
      console.warn("No token available");
      window.open(url, "_blank");
    }
  }

  fetchAndOpenInNewTab(url: string, token: string) {
    fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Vulnerable-Mode": this.vulnerableModeAccess.toString(),
      },
    })
      .then((response) => response.text())
      .then((html) => {
        const newWindow = window.open("", "_blank");
        if (newWindow) {
          newWindow.document.write(html);
          newWindow.document.close();
        }
      })
      .catch((error) => {
        console.error("Error fetching page:", error);
        alert("Greška pri dohvaćanju stranice");
      });
  }
}

const API_URL = "http://localhost:3000";

interface ResponseServer {
  type: "ERROR" | "SUCCESS";
  message: string;
  access_token?: string;
  refresh_token?: string;
}

export async function refreshAcessToken() {
  const now_date = new Date().toLocaleDateString();
  const before_date = localStorage.getItem("before_date");
  const local_refresh_token = localStorage.getItem("refresh_token");

  if (now_date === before_date || !local_refresh_token) {
    return;
  }

  const response = await fetch(API_URL + "/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      refresh_token: local_refresh_token,
    }),
  });

  const data: ResponseServer = await response.json();

  if (!data) {
    return;
  }

  if (data.type === 'ERROR') {
    
    if (!data.access_token) {
        return;
    }

    localStorage.setItem("before_date", new Date().toLocaleDateString());
    localStorage.setItem("access_token", data.access_token);
  }
}

/*export function apiFecth(endpoint: string, option: RequestInit) {
    const acessToken = localStorage.getItem('access_token')




}
*/

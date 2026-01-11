/**
 * Phosphor Icons - Local Loading
 * Loads phosphor icon styles from local staticfiles (no external CDNs)
 * Complies with strict Content Security Policy
 */
var head = document.getElementsByTagName("head")[0];
var baseUrl = "/static/assets/css/phosphor/";

for (const weight of ["regular", "thin", "light", "bold", "fill", "duotone"]) {
  var link = document.createElement("link");
  link.rel = "stylesheet";
  link.type = "text/css";
  link.href = baseUrl + weight + ".css";
  head.appendChild(link);
}

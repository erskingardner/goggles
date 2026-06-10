// Light/dark theme toggle. The initial theme is applied by an inline
// <head> script before first paint; this module only handles switching.
const toggle = document.getElementById("theme-toggle");

if (toggle) {
  toggle.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("goggles-theme", next);
    } catch {
      // private mode etc. — theme still flips for this page
    }
  });
}

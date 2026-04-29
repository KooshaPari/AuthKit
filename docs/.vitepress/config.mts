import { defineConfig } from "vitepress";

export default defineConfig({
  title: "AuthKit",
  description: "Unified cross-platform authentication SDK for the Phenotype ecosystem.",
  base: process.env.GITHUB_PAGES === "true" ? "/AuthKit/" : "/",
  cleanUrls: true,
  lastUpdated: true,
  themeConfig: {
    nav: [
      { text: "Overview", link: "/" },
      { text: "Protocols", link: "/protocols" },
      { text: "Packages", link: "/packages" },
      { text: "Requirements", link: "/FUNCTIONAL_REQUIREMENTS" },
      { text: "GitHub", link: "https://github.com/KooshaPari/AuthKit" },
    ],
    sidebar: [
      {
        text: "AuthKit",
        items: [
          { text: "Overview", link: "/" },
          { text: "Protocol Scope", link: "/protocols" },
          { text: "Package Surfaces", link: "/packages" },
          { text: "Functional Requirements", link: "/FUNCTIONAL_REQUIREMENTS" },
        ],
      },
    ],
    socialLinks: [{ icon: "github", link: "https://github.com/KooshaPari/AuthKit" }],
    search: {
      provider: "local",
    },
  },
});

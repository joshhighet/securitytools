// script.js

new Vue({
  el: "#app",
  data: {
    data: [],
    loading: true,
    searchQuery: "",
    sortKey: "stars",
    sortDirection: -1,
    selectedTags: [],
  },
  computed: {
    sortedData() {
      return this.data.slice().sort((a, b) => {
        const valA = this.sortKey === "location"
          ? this.repoLabel(a)
          : this.sortKey === "description"
            ? (a.description || "")
            : (a[this.sortKey] || 0);
        const valB = this.sortKey === "location"
          ? this.repoLabel(b)
          : this.sortKey === "description"
            ? (b.description || "")
            : (b[this.sortKey] || 0);

        if (typeof valA === "string") {
          return this.sortDirection * valA.localeCompare(valB);
        }
        return this.sortDirection * (valA - valB);
      });
    },
    filteredData() {
      const q = this.searchQuery.toLowerCase();
      return this.sortedData.filter((repo) => {
        const label = this.repoLabel(repo).toLowerCase();
        const desc  = (repo.description || "").toLowerCase();
        const tags  = this.getTags(repo);

        const matchesSearch = !q || label.includes(q) || desc.includes(q);
        const matchesTags   = this.selectedTags.every((t) => tags.includes(t));

        return matchesSearch && matchesTags;
      });
    },
    uniqueTagCount() {
      const seen = new Set();
      this.data.forEach((repo) => this.getTags(repo).forEach((t) => seen.add(t)));
      return seen.size;
    },
  },
  async created() {
    try {
      const response = await fetch(
        "https://raw.githubusercontent.com/joshhighet/securitytools/main/docs/directory.json"
      );
      this.data = await response.json();
    } finally {
      this.loading = false;
    }
  },
  methods: {
    repoLabel(repo) {
      try {
        const parts = repo.url.split("/");
        return parts[3] + "/" + parts[4].replace(/\.git$/, "");
      } catch {
        return repo.url || "";
      }
    },
    getTags(repo) {
      if (!repo.path) return [];
      return repo.path.replace("projects/", "").split("/").slice(0, -1);
    },
    sortBy(key) {
      if (this.sortKey === key) {
        this.sortDirection = -this.sortDirection;
      } else {
        this.sortKey = key;
        this.sortDirection = key === "location" || key === "description" ? 1 : -1;
      }
    },
    toggleTag(tag) {
      const idx = this.selectedTags.indexOf(tag);
      if (idx >= 0) {
        this.selectedTags.splice(idx, 1);
      } else {
        this.selectedTags.push(tag);
      }
    },
    generateTagColor(tag) {
      let hash = 0;
      for (let i = 0; i < tag.length; i++) {
        hash = tag.charCodeAt(i) + ((hash << 5) - hash);
      }
      const hue = Math.abs(hash) % 360;
      return `hsl(${hue}, 55%, 38%)`;
    },
  },
});

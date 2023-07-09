// app.js

new Vue({
    el: "#app",
    data: {
      data: [],
      searchQuery: "",
      sortKey: "stars",
      sortDirection: -1,
      selectedTags: [],
    },
    computed: {
      sortedData() {
        return this.data
          .slice()
          .sort((a, b) => this.sortDirection * (a[this.sortKey] - b[this.sortKey]));
      },
      filteredData() {
        return this.sortedData.filter((repository) => {
          const location =
            repository.url.split("/")[3] +
            "/" +
            repository.url.split("/")[4].split(".")[0];
          const description = repository.description || "";
          const tags = repository.path
            .replace("projects/", "")
            .split("/")
            .slice(0, -1);
  
          const tagFilter = this.selectedTags.every((tag) => tags.includes(tag));
  
          return (
            tagFilter &&
            (description.toLowerCase().includes(this.searchQuery.toLowerCase()) ||
              location.toLowerCase().includes(this.searchQuery.toLowerCase()))
          );
        });
      },
    },
    async created() {
      const response = await fetch(
        "https://raw.githubusercontent.com/joshhighet/securitytools/main/docs/directory.json"
      );
      this.data = await response.json();
    },
    methods: {
      sortBy(key) {
        this.sortDirection = this.sortKey === key ? -this.sortDirection : -1;
        this.sortKey = key;
      },
      toggleTag(tag) {
        const index = this.selectedTags.indexOf(tag);
        if (index >= 0) {
          this.selectedTags.splice(index, 1);
        } else {
          this.selectedTags.push(tag);
        }
      },
      generateTagColor(tag) {
        let hash = 0;
        for (let i = 0; i < tag.length; i++) {
          hash = tag.charCodeAt(i) + ((hash << 5) - hash);
        }
  
        const c = (hash & 0x00ffffff).toString(16).toUpperCase();
        const color = "00000".substring(0, 6 - c.length) + c;
  
        return "#" + color;
      },
    },
  });
  
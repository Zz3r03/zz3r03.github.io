// Load posts from the JSON file
let postsByType = {};

async function loadPosts() {
    const response = await fetch(`/src/posts.json?${new Date().getTime()}`); // Cache-busting query parameter
    postsByType = await response.json();
}

// Function to toggle dropdown visibility
function toggleDropdown(type) {
    const dropdown = document.getElementById(`${type}Dropdown`);
    if (dropdown.style.display === "block") {
        dropdown.style.display = "none";
    } else {
        dropdown.style.display = "block";
    }
}

// Function to filter and display posts by type and tag
function searchPosts(type) {
    const searchTerm = document.getElementById(`${type}Search`).value.trim().toLowerCase();
    const resultsContainer = document.getElementById(`${type}Results`);
    resultsContainer.innerHTML = ''; // Clear previous results

    if (!searchTerm) {
        resultsContainer.innerHTML = '<p>No results.</p>';
        return;
    }

    const filteredPosts = postsByType[type].filter(post => 
        post.tags.some(tag => tag.toLowerCase().includes(searchTerm))
    );

    if (filteredPosts.length === 0) {
        resultsContainer.innerHTML = '<p>No posts found.</p>';
        return;
    }

    filteredPosts.forEach(post => {
        const postLink = document.createElement('a');
        postLink.href = post.url;
        postLink.textContent = post.title;
        resultsContainer.appendChild(postLink);
    });
}

// Function to hide the menu
function hideMenu() {
    const sideMenu = document.getElementById('sideMenu');
    sideMenu.classList.remove('visible');
    document.body.classList.remove('menu-visible');
}

// Function to toggle the menu visibility
function toggleMenu() {
    const sideMenu = document.getElementById('sideMenu');
    sideMenu.classList.toggle('visible');
    document.body.classList.toggle('menu-visible');
}

// Load posts when the page loads
window.onload = loadPosts;

// Search Menu Functionality
const searchMenu = document.getElementById('searchMenu');
const searchInput = document.getElementById('searchInput');
const searchResults = document.getElementById('searchResults');
const cancelBtn = document.getElementById('cancelBtn');

// Function to toggle the search menu
function toggleSearchMenu() {
    searchMenu.classList.toggle('visible');
    if (searchMenu.classList.contains('visible')) {
        searchInput.focus(); // Focus the input when the menu is shown
    } else {
        searchInput.value = ''; // Clear the input when the menu is hidden
        searchResults.innerHTML = ''; // Clear the results
    }
}

// Listen for the "s" key press
document.addEventListener('keydown', (event) => {
    // Only toggle the search menu if the search input is not focused
    if ((event.key === 's' || event.key === 'S') && document.activeElement !== searchInput) {
        event.preventDefault(); // Prevent the "s" key from being typed
        toggleSearchMenu();
    }
});

// Close the search menu when clicking the cancel button
cancelBtn.addEventListener('click', () => {
    toggleSearchMenu();
});

// Close the search menu when clicking outside of it
document.addEventListener('click', (event) => {
    if (
        searchMenu.classList.contains('visible') &&
        !searchMenu.contains(event.target) &&
        event.target !== searchInput
    ) {
        toggleSearchMenu();
    }
});

// Search functionality
searchInput.addEventListener('input', () => {
    const query = searchInput.value.trim().toLowerCase();
    searchResults.innerHTML = ''; // Clear previous results

    if (query) {
        // Flatten all posts into a single array for searching
        const allPosts = Object.values(postsByType).flat();

        // Check if the query includes a type filter (e.g., "walkthrough: javascript")
        const typeFilter = query.startsWith("walkthrough:") ? "walkthrough" :
                           query.startsWith("protocol:") ? "protocol" :
                           query.startsWith("tool:") ? "tool" :
                           query.startsWith("other:") ? "other" :
                           null;

        const searchTerm = typeFilter ? query.split(":")[1].trim() : query;

        const filteredPosts = allPosts.filter(post => {
            // Filter by type if a type filter is specified
            if (typeFilter && post.type !== typeFilter) {
                return false;
            }
            // Filter by title or tags
            return (
                post.title.toLowerCase().includes(searchTerm) ||
                post.tags.some(tag => tag.toLowerCase().includes(searchTerm))
            );
        });

        if (filteredPosts.length > 0) {
            filteredPosts.forEach(post => {
                const link = document.createElement('a');
                link.href = post.url;
                link.textContent = `${post.title} - ${post.type}`; // Show post type in results
                link.classList.add('search-result-item');
                searchResults.appendChild(link);
            });
        } else {
            searchResults.innerHTML = '<p>No results found.</p>';
        }
    } else {
        searchResults.innerHTML = '<p>Enter a search term.</p>';
    }
});
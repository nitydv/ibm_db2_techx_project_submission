function getLocation() {

    const locationText = document.getElementById("location");

    if (!navigator.geolocation) {
        locationText.innerText =
            "Geolocation is not supported.";
        return;
    }

    locationText.innerText = "Getting location...";

    navigator.geolocation.getCurrentPosition(

        function(position) {

            const latitude = position.coords.latitude;
            const longitude = position.coords.longitude;

            locationText.innerText =
                "Latitude: " + latitude +
                " | Longitude: " + longitude;
        },

        function() {

            locationText.innerText =
                "Unable to get location.";
        }

    );
}
function getLocation() {

    const locationText =
        document.getElementById("location");

    if (!navigator.geolocation) {

        locationText.innerText =
            "Geolocation is not supported.";

        return;
    }

    locationText.innerText =
        "Getting your location...";


    navigator.geolocation.getCurrentPosition(

        function(position) {

            const latitude =
                position.coords.latitude;

            const longitude =
                position.coords.longitude;


            document.getElementById("latitude").value =
                latitude;

            document.getElementById("longitude").value =
                longitude;


            locationText.innerText =
                "📍 Location captured successfully";

        },

        function(error) {

            locationText.innerText =
                "Unable to get location.";

        }

    );
}

/* ==================================
   RESQNET INCIDENT SEARCH ENGINE
================================== */

document.addEventListener("DOMContentLoaded", function () {

    const searchInput = document.getElementById("incidentSearch");
    const statusFilter = document.getElementById("statusFilter");
    const severityFilter = document.getElementById("severityFilter");
    const resetButton = document.getElementById("resetFilters");
    const incidentCount = document.getElementById("incidentCount");

    if (
        !searchInput ||
        !statusFilter ||
        !severityFilter ||
        !resetButton ||
        !incidentCount
    ) {
        return;
    }

    /*
      Existing dashboard table ki rows identify karein.
      Table ke andar header row ko filter nahi kiya jayega.
    */

    const tables = document.querySelectorAll("table");
    let incidentRows = [];

    tables.forEach(function (table) {
        const rows = table.querySelectorAll("tbody tr");

        rows.forEach(function (row) {
            incidentRows.push(row);
        });
    });

    function filterIncidents() {

        const searchText = searchInput.value
            .trim()
            .toLowerCase();

        const selectedStatus = statusFilter.value;
        const selectedSeverity = severityFilter.value;

        let visibleCount = 0;

        incidentRows.forEach(function (row) {

            const rowText = row.innerText.toLowerCase();

            const matchesSearch =
                rowText.includes(searchText);

            /*
              Dashboard table mein status aur severity
              ke columns ki position alag ho sakti hai.
              Isliye text-based matching use kar rahe hain.
            */

            const matchesStatus =
                selectedStatus === "all" ||
                rowText.includes(selectedStatus);

            const matchesSeverity =
                selectedSeverity === "all" ||
                rowText.includes(selectedSeverity);

            const visible =
                matchesSearch &&
                matchesStatus &&
                matchesSeverity;

            row.style.display = visible ? "" : "none";

            if (visible) {
                visibleCount++;
            }
        });

        incidentCount.textContent =
            "Showing " + visibleCount +
            " of " + incidentRows.length +
            " incident rows";
    }

    searchInput.addEventListener("input", filterIncidents);
    statusFilter.addEventListener("change", filterIncidents);
    severityFilter.addEventListener("change", filterIncidents);

    resetButton.addEventListener("click", function () {

        searchInput.value = "";
        statusFilter.value = "all";
        severityFilter.value = "all";

        filterIncidents();
    });

    filterIncidents();

});
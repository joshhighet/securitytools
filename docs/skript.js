var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://raw.githubusercontent.com/joshhighet/securitytools/release/docs/directori.json', true);
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4) {
    var data = JSON.parse(xhr.responseText);
    var table = document.createElement('table');
    var tableBody = document.createElement('tbody');
    data.forEach(function(rowData) {
      var row = document.createElement('tr');
      Object.keys(rowData).forEach(function(key) {
        var cell = document.createElement('td');
        var cellText = document.createTextNode(rowData[key]);
        cell.appendChild(cellText);
        row.appendChild(cell);
      });
      tableBody.appendChild(row);
    });
    table.appendChild(tableBody);
    document.body.appendChild(table);
  }
}
xhr.send();

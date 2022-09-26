var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://raw.githubusercontent.com/joshhighet/securitytools/release/docs/directori.json', true);
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4) {
    var data = JSON.parse(xhr.responseText);
    var table = document.createElement('table');
    var tr = document.createElement('tr');
    var th = document.createElement('th');
    th.innerHTML = 'path';
    tr.appendChild(th);
    th = document.createElement('th');
    th.innerHTML = 'url';
    tr.appendChild(th);
    th = document.createElement('th');
    th.innerHTML = 'description';
    tr.appendChild(th);
    th = document.createElement('th');
    th.innerHTML = 'watchers';
    tr.appendChild(th);
    th = document.createElement('th');
    th.innerHTML = 'forks';
    tr.appendChild(th);
    th = document.createElement('th');
    th.innerHTML = 'stars';
    tr.appendChild(th);
    table.appendChild(tr);
    for (var i = 0; i < data.length; i++) {
      tr = document.createElement('tr');
      var td = document.createElement('td');
      td.innerHTML = data[i].path;
      tr.appendChild(td);
      td = document.createElement('td');
      td.innerHTML = data[i].url;
      tr.appendChild(td);
      td = document.createElement('td');
      td.innerHTML = data[i].description;
      tr.appendChild(td);
      td = document.createElement('td');
      td.innerHTML = data[i].watchers;
      tr.appendChild(td);
      td = document.createElement('td');
      td.innerHTML = data[i].forks;
      tr.appendChild(td);
      td = document.createElement('td');
      td.innerHTML = data[i].stars;
      tr.appendChild(td);
      table.appendChild(tr);
    }
    document.body.appendChild(table);
  }
}
xhr.send();

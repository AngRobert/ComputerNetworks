var express = require('express');
var path = require('path');
var logger = require('morgan');

var app = express();

app.use(logger('dev'));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/users', function(req, res) {
  res.send('respond with a resource');
});

app.use(function(req, res) {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.send('Error: ' + (err.status || 500) + ' - ' + err.message);
});

var port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', function() {
  console.log('Server listening on port ' + port);
});

module.exports = app;

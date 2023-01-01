# Reverse Tunnel Usage

## server:

```
node index.js
```


## client:

```
ssh -i foo foo@localhost -p 1337 -R 3002:localhost:3000
```

## REST API

### add key

```
curl -X POST -H "Content-Type:application/json" http://localhost:8081/servers -d '{"pubKeyBase64":"AAAAC3NzaC1lZDI1NTE5AAAAIGT5YCsCcD7i+BcZmluhu+7Jdc54lRekIyMh+cWRqYT8"}'
```

### list registered keys

```
curl http://localhost:8081/servers
```

### read registered key

```
curl http://localhost:8081/servers/17WTLmdATqtbHiqFHCj92o6e3V6rmQVKuQ
```


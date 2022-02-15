# Meta X project API

## Prerequisites


* JDK 11 +

2. Build the project.
```
mvn package
```

3. Build docker image.
```
docker build -t tender-bid-api .
```

4. Tag.
```
docker tag tender-bid-api sonhn98/tender-bid-api
```

5. Docker hub.
```
docker push sonhn98/tender-bid-api
```

6. Run.
```
docker run -d -it  -p 8000:8000/tcp --name tender-bid-api sonhn98/tender-bid-api:latest
```

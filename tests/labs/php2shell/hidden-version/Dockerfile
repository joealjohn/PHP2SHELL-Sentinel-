FROM nginx:1.25-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN echo '<html><body><h1>hidden-version lab</h1><p>Local PHP2Shell test target. Never expose to the internet.</p></body></html>' > /usr/share/nginx/html/index.html

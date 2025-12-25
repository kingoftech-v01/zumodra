# Nginx Dockerfile for Zumodra

FROM nginx:1.25-alpine

# Remove default nginx configuration
RUN rm /etc/nginx/conf.d/default.conf

# Copy our custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/

# Create directory for Let's Encrypt challenges
RUN mkdir -p /var/www/certbot

# Set permissions
RUN chown -R nginx:nginx /var/www/certbot

# Expose ports
EXPOSE 80 443

# Start nginx
CMD ["nginx", "-g", "daemon off;"]

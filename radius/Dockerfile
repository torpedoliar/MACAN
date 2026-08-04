FROM freeradius/freeradius-server:latest
RUN ln -s /etc/raddb/mods-available/sql /etc/raddb/mods-enabled/sql || true
COPY sql.conf /etc/raddb/mods-available/sql
COPY queries.conf /etc/raddb/mods-config/sql/main/mysql/queries.conf
COPY default.conf /etc/raddb/sites-enabled/default
# Dynamic clients: replaces the upstream clients.conf (which ships a hardcoded
# localhost/testing123 entry) and adds the virtual server that resolves a source
# IP to its row in the controllers table.
COPY clients.conf /etc/raddb/clients.conf
COPY macan_clients.conf /etc/raddb/sites-enabled/macan_clients

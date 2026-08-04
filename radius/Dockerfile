FROM freeradius/freeradius-server:latest
RUN ln -s /etc/raddb/mods-available/sql /etc/raddb/mods-enabled/sql || true
COPY sql.conf /etc/raddb/mods-available/sql
COPY queries.conf /etc/raddb/mods-config/sql/main/mysql/queries.conf
COPY default.conf /etc/raddb/sites-enabled/default

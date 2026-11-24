# Supply a reviewed ephemeral base tag/digest; pin the resulting image in catalog.
ARG BASE=agentbox/ephemeral:local
FROM ${BASE}
USER root
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers \
    NODE_PATH=/opt/agentbox-browser/node_modules \
    XDG_CACHE_HOME=/tmp/agentbox-browser-cache \
    XDG_CONFIG_HOME=/tmp/agentbox-browser-config
COPY images/research-browser/package.json images/research-browser/package-lock.json /opt/agentbox-browser/
RUN cd /opt/agentbox-browser \
 && npm ci --omit=dev --ignore-scripts \
 && ./node_modules/.bin/playwright install --with-deps --only-shell chromium \
 && ln -s /opt/agentbox-browser/node_modules/.bin/playwright /usr/local/bin/playwright \
 && chmod -R a+rX /opt/playwright-browsers /opt/agentbox-browser \
 && npm cache clean --force \
 && rm -rf /var/lib/apt/lists/*
COPY images/research-browser/research-browser.cjs /usr/local/bin/research-browser
RUN chmod 0755 /usr/local/bin/research-browser
USER agent

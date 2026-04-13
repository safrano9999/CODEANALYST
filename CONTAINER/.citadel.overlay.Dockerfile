FROM localhost/citadelbasic:base

# Repo payload
COPY CODEANALYST /opt/CODEANALYST

# Python deps (optional)
RUN if [ -f /opt/CODEANALYST/requirements.txt ]; then \
      python3 -m pip install --no-cache-dir -r /opt/CODEANALYST/requirements.txt; \
    fi

# Keep module+runtime metadata inside image
RUN mkdir -p /opt/citadel/modules/codeanalyst
COPY CODEANALYST/CONTAINER/module.toml /opt/citadel/modules/codeanalyst/module.toml
COPY CODEANALYST/CONTAINER/runtime.toml /opt/citadel/modules/codeanalyst/runtime.toml

# Module-level runtime append via supervisord conf.d
COPY CODEANALYST/CONTAINER/.citadel.module.supervisord.conf /etc/supervisor/conf.d/zz-module-codeanalyst.conf

from .generic import generic_profile
from .nginx import nginx_profile
from .tomcat import tomcat_profile
from .python_web import python_web_profile
from .node_web import node_web_profile
from .spring_boot import spring_boot_profile

__all__ = [
    "generic_profile",
    "nginx_profile",
    "tomcat_profile",
    "python_web_profile",
    "node_web_profile",
    "spring_boot_profile",
]
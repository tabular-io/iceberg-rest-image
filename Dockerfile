#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
FROM azul/zulu-openjdk:17

RUN \
    set -xeu && \
    groupadd iceberg --gid 1000 && \
    useradd iceberg --uid 1000 --gid 1000 --create-home

COPY --chown=iceberg:iceberg build/libs /usr/lib/iceberg-rest

EXPOSE 8181
USER iceberg:iceberg
ENV LANG en_US.UTF-8
WORKDIR /usr/lib/iceberg-rest
CMD ["java", "-cp", "./*", "org.apache.iceberg.rest.RESTCatalogAdapter"]

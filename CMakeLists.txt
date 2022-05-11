cmake_minimum_required(VERSION 3.10)
project(l3afd)

add_custom_target(swagger ALL
                  DEPENDS ${CMAKE_SOURCE_DIR}/docs/docs.go
                          ${CMAKE_SOURCE_DIR}/docs/swagger.json
                          ${CMAKE_SOURCE_DIR}/docs/swagger.yaml)

add_custom_command(OUTPUT $ENV{GOPATH}/bin/swag.exe
                   COMMAND go install github.com/swaggo/swag/cmd/swag@latest
                   COMMAND go get -u github.com/swaggo/http-swagger
                   COMMAND go get -u github.com/alecthomas/template)

add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/docs/docs.go
                          ${CMAKE_SOURCE_DIR}/docs/swagger.json
                          ${CMAKE_SOURCE_DIR}/docs/swagger.yaml
                   DEPENDS ${CMAKE_SOURCE_DIR}/apis/configwatch.go
                           $ENV{GOPATH}/bin/swag.exe
                   WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                   COMMAND env
                   COMMAND "$ENV{GOPATH}/bin/swag.exe" init -d "./" -g "apis/configwatch.go")

add_custom_target(build ALL
                  DEPENDS ${CMAKE_SOURCE_DIR}/l3afd.exe)

if (${WIN32})
  add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/l3afd.exe
                     DEPENDS ${CMAKE_SOURCE_DIR}/main.go
                     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                     COMMAND go build -tags WINDOWS .)
else ()
  add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/l3afd.exe
                     DEPENDS ${CMAKE_SOURCE_DIR}/main.go
                     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                     COMMAND go build .)
endif ()

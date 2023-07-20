add_vanetza_component(pki
    authorization_tickets.cpp
    curl_wrapper.cpp
    enrolment_certificates.cpp
    authorization_tickets.cpp
)
target_link_libraries(pki PUBLIC common net asn1 security curl)

add_test_subdirectory(tests)

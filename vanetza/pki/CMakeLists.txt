add_vanetza_component(pki
    authorization_tickets.cpp
    curl_wrapper.cpp
    ectl_trust_store.cpp
    enrolment_certificates.cpp
)
target_link_libraries(pki PUBLIC common net asn1 security curl boost_filesystem)

add_test_subdirectory(tests)

add_vanetza_component(pki
    enrolment_certificates.cpp
)
target_link_libraries(pki PUBLIC common net asn1 security)

add_test_subdirectory(tests)

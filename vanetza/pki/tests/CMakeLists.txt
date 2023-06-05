include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES pki)

add_gtest(EnrolmentCertificates enrolment_certificates.cpp)

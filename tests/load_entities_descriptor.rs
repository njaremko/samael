use samael::metadata::EntitiesDescriptor;

#[test]
fn load_entities_descriptor() {
    let descriptor: EntitiesDescriptor = yaserde::de::from_str(include_str!(
        "../test_vectors/preview-renater-imt-metadata.xml"
    ))
    .unwrap();
    let descriptor_xml = yaserde::ser::to_string(&descriptor).unwrap();
    let loaded_descriptor: EntitiesDescriptor = yaserde::de::from_str(&descriptor_xml).unwrap();
    assert_eq!(loaded_descriptor, descriptor);
}

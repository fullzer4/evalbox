def test_import():
    import pyenclave
    assert hasattr(pyenclave, "__version__")
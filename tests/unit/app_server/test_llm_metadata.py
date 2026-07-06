from uuid import uuid4

from openhands.app_server.utils.llm_metadata import get_llm_metadata


def test_get_llm_metadata_without_repository():
    metadata = get_llm_metadata(
        model_name='openhands/o3',
        llm_type='agent',
        conversation_id=uuid4(),
        user_id='test-user',
    )
    assert 'repository' not in metadata
    assert not any(tag.startswith('repository:') for tag in metadata['tags'])


def test_get_llm_metadata_with_repository():
    metadata = get_llm_metadata(
        model_name='openhands/o3',
        llm_type='agent',
        conversation_id=uuid4(),
        user_id='test-user',
        selected_repository='my-org/my-repo',
    )
    assert metadata['repository'] == 'my-org/my-repo'
    assert 'repository:my-org/my-repo' in metadata['tags']

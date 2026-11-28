from db.forum import ForumDb


def test_forum(tmp_path):
    forum = ForumDb(str(tmp_path / "forum.db"), 7001, 7002)
    try:
        forum.create_forum_table()
        fid = forum.create_forum("TouchFish Main Forum", 0, "First forum")
        first = forum.send_post(fid, 0, "Welcome to TouchFish V5!", "First post")
        second = forum.send_post(fid, 0, "Another post", "Second post")

        assert {row[1] for row in forum.query_all_post(fid)} == {first, second}
        forum.delete_post(fid, first)
        assert [row[1] for row in forum.query_all_post(fid)] == [second]

        forum.clean_user_content(0)
        assert not forum.query_forum_creater(0)
    finally:
        forum.conn.close()

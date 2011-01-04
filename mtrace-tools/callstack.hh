struct CallStack {
	CallStack(struct mtrace_fcall_entry *f) {
		start_ = f;
	}
	
	void complete(void) {
		
	}
	
	struct mtrace_fcall_entry *start_;
};

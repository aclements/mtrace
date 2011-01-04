using namespace::std;

struct CallInterval {
	uint64_t id_;
	uint64_t call_trace_tag_;
	
	uint64_t start_pc_;
	uint64_t end_pc_;

	uint64_t start_count_;
	uint64_t end_count_;

	uint64_t prev_;
	uint64_t next_;
	uint64_t ret_;
};

struct CallStack {
	CallStack(struct mtrace_fcall_entry *f) {
		start_ = f;
		current_ = NULL;
	}

	void push(struct mtrace_call_entry *f) {
		end_current(f->access_count);
		
		current_ = new CallInterval();
		current_->start_count_ = f->access_count;
		current_->id_ = ++call_interval_count;
		current_->start_pc_ = f->target_pc;
	}

	void pop(struct mtrace_call_entry *f) {
		end_current(f->access_count);

		current_ = new CallInterval();
		current_->start_count_ = f->access_count;
		current_->id_ = ++call_interval_count;
		current_->start_pc_ = f->target_pc;
	}

	void end_current(uint64_t end_count) {
		if (current_ != NULL) {
			current_->end_count_ = end_count;
			timeline_.push_back(current_);
			current_ = NULL;
		}
	}

	CallInterval			*current_;
	struct mtrace_fcall_entry 	*start_;
	list<CallInterval *> 		timeline_;

	static uint64_t   		call_interval_count;
};

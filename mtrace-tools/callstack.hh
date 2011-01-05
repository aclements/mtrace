using namespace::std;

struct CallInterval {
	uint64_t id_;
	uint64_t call_trace_tag_;
	int	 cpu_;
	
	uint64_t start_pc_;
	uint64_t end_pc_;

	uint64_t access_start_;
	uint64_t access_end_;

	uint64_t prev_;
	uint64_t next_;
	uint64_t ret_;
};

struct CallTrace {
	CallTrace(struct mtrace_fcall_entry *f) {
		start_ = f;
		current_ = NULL;
	}

	void push(struct mtrace_call_entry *f) {
		end_current(f->h.access_count);
		
		current_ = new CallInterval();
		current_->access_start_ = f->h.access_count;
		current_->id_ = ++call_interval_count;
		current_->cpu_ = f->h.cpu;
		current_->start_pc_ = f->target_pc;
	}

	void pop(struct mtrace_call_entry *f) {
		end_current(f->h.access_count);

		current_ = new CallInterval();
		current_->access_start_ = f->h.access_count;
		current_->id_ = ++call_interval_count;
		current_->start_pc_ = f->target_pc;
	}

	void end_current(uint64_t end_count) {
		if (current_ != NULL) {
			if (!timeline_.empty()) {
				CallInterval *prev;
				prev = timeline_.back();

				prev->next_ =  current_->id_;
				current_->prev_ = prev->id_;
			}

			current_->access_end_ = end_count;
			timeline_.push_back(current_);
			current_ = NULL;
		}
	}

	CallInterval			*current_;
	struct mtrace_fcall_entry 	*start_;
	list<CallInterval *> 		timeline_;

	static uint64_t   		call_interval_count;
};
